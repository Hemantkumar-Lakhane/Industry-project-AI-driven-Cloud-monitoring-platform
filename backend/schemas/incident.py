"""
Security Incident Schema for RAM Antivirus
============================================
Defines the higher-level SecurityIncident model representing a correlated
attack campaign or security incident composed of multiple atomic findings.
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, field_validator, ConfigDict


class SecurityIncident(BaseModel):
    """
    Higher-level incident grouping related security findings.
    Preserves all atomic findings while presenting an enterprise campaign view.
    """
    model_config = ConfigDict(extra="ignore")

    incident_id: str = Field(..., description="Unique deterministic incident identifier (e.g. INC-A1B2C3D4)")
    title: str = Field(..., description="High-level incident title reflecting primary attack campaign")
    description: str = Field(default="", description="Detailed narrative of the correlated campaign")
    severity: str = Field(default="medium", description="Highest severity among member findings (critical, high, medium, low, info)")
    status: str = Field(default="open", description="open, investigating, contained, resolved")

    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Earliest finding timestamp in UTC")
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Latest finding timestamp in UTC")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Duration in seconds between first and last finding")

    finding_count: int = Field(default=1, ge=1, description="Number of correlated security findings")
    finding_ids: List[str] = Field(default_factory=list, description="IDs of all member findings")

    principals: List[str] = Field(default_factory=list, description="Unique identities involved")
    source_ips: List[str] = Field(default_factory=list, description="Unique source IPs involved")
    resources: List[str] = Field(default_factory=list, description="Unique affected resources")

    attack_categories: List[str] = Field(default_factory=list, description="Unique attack categories involved")
    attack_stages: List[str] = Field(default_factory=list, description="MITRE kill-chain stages involved")

    correlation_score: float = Field(default=0.85, ge=0.0, le=1.0, description="Deterministic confidence score of the correlation")
    correlation_reasons: List[str] = Field(default_factory=list, description="Deterministic evidence backing the correlation")

    primary_playbook_id: Optional[str] = Field(default=None, description="Primary recommended playbook ID")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Full or summarized records of member findings")

    @field_validator("start_time", "last_seen", mode="before")
    @classmethod
    def parse_incident_timestamps(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            try:
                clean_str = v.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(clean_str)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except Exception:
                return datetime.now(timezone.utc)
        return datetime.now(timezone.utc)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> str:
        if not isinstance(v, str):
            return "medium"
        val = v.strip().lower()
        if val in ("critical", "high", "medium", "low", "info"):
            return val
        return "medium"

    def __getitem__(self, item: str) -> Any:
        if item == "entity_name":
            return self.principals[0] if self.principals else (self.resources[0] if self.resources else "unknown")
        if item == "phases_detected":
            phases = []
            for st in self.attack_stages:
                for phase in ["Reconnaissance", "Initial Access", "Privilege Escalation", "Execution", "Defense Evasion", "Exfiltration", "Collection", "Impact"]:
                    if phase.lower() in st.lower() and phase not in phases:
                        phases.append(phase)
            for cat in self.attack_categories:
                phase = {
                    "network_scanning": "Reconnaissance",
                    "cloud_misconfiguration": "Reconnaissance",
                    "brute_force": "Initial Access",
                    "bola_ssrf": "Initial Access",
                    "supply_chain": "Initial Access",
                    "iam_privilege_escalation": "Privilege Escalation",
                    "account_takeover": "Privilege Escalation",
                    "defense_tampering": "Defense Evasion",
                    "suspicious_api_activity": "Defense Evasion",
                    "container_k8s_attacks": "Execution",
                    "serverless_abuse": "Execution",
                    "malware_ransomware": "Execution",
                    "data_exfiltration": "Exfiltration",
                    "database_attacks": "Collection",
                    "cryptomining": "Impact",
                    "ddos": "Impact"
                }.get(cat)
                if phase and phase not in phases:
                    phases.append(phase)
            return phases or self.attack_stages
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default

