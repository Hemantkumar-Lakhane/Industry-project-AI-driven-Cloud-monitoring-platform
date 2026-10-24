"""
Normalized Event Schema for RAM Antivirus
==========================================
Standardized, validated Pydantic schema for all incoming telemetry events
across heterogeneous log sources (Wazuh, AWS CloudTrail, VPC Flow, K8s, host syslogs).
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict


class PrincipalInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    identity: str = Field(default="unknown", description="Username, IAM user, or service account name")
    principal_type: str = Field(default="unknown", description="IAMUser, IAMRole, Root, ServiceAccount, HostUser")
    arn: Optional[str] = Field(default=None, description="Cloud Resource Name or identity URI")


class NetworkInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    src_ip: str = Field(default="unknown", description="Source IPv4/IPv6 address")
    dst_ip: str = Field(default="unknown", description="Destination IPv4/IPv6 address")
    src_port: Optional[int] = Field(default=None, description="Source TCP/UDP port")
    dst_port: Optional[int] = Field(default=None, description="Destination TCP/UDP port")
    protocol: Optional[str] = Field(default=None, description="TCP, UDP, ICMP, HTTPS, SSH, etc.")


class EventProvenance(BaseModel):
    model_config = ConfigDict(extra="ignore")
    collector: str = Field(default="ram_agent", description="Ingestion agent or log collector ID")
    ingest_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Ingestion timestamp in UTC")
    ingest_mode: str = Field(default="live", description="live, imported, or simulated")


class NormalizedEvent(BaseModel):
    """
    Unified representation of an observable workload event.
    Guarantees consistent data fields for downstream feature extraction,
    deterministic rule engines, and statistical ML anomaly models.
    """
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: f"EVT-{str(uuid.uuid4())[:8]}", description="Unique event identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of event occurrence in UTC")
    source_type: str = Field(default="wazuh", description="Telemetry source: wazuh, cloudtrail, vpc_flow, k8s_audit, host_audit, synthetic")
    source_identifier: Optional[str] = Field(default=None, description="Specific stream, file, or cloud resource ARN")
    
    principal: PrincipalInfo = Field(default_factory=PrincipalInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    
    service: Optional[str] = Field(default=None, description="Target service: iam, s3, ec2, ssh, http, etc.")
    action: str = Field(default="unknown", description="API call, system operation, or event verb")
    target_resource: Optional[str] = Field(default=None, description="Target resource ARN, file path, or bucket name")
    status: str = Field(default="unknown", description="success, failure, error, detected, blocked")
    
    # Operational flow metrics (operational only, strictly zero target leakage)
    duration: float = Field(default=0.0, ge=0.0, description="Flow connection duration in seconds")
    src_bytes: int = Field(default=0, ge=0, description="Payload bytes sent from source")
    dst_bytes: int = Field(default=0, ge=0, description="Payload bytes sent from destination")
    failed_attempts: int = Field(default=0, ge=0, description="Consecutive failed attempts or error counts")
    
    # Connection burst and error statistics (used for flow feature extraction)
    count: int = Field(default=1, ge=0, description="Connections to same host in sliding window")
    srv_count: int = Field(default=1, ge=0, description="Connections to same service in sliding window")
    serror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of SYN error connections [0.0, 1.0]")
    rerror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of REJ error connections [0.0, 1.0]")
    same_srv_rate: float = Field(default=1.0, ge=0.0, le=1.0, description="Ratio of connections to same service [0.0, 1.0]")
    diff_srv_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of connections to different services [0.0, 1.0]")
    
    description: Optional[str] = Field(default="", description="Human-readable event summary")
    rule_id: Optional[int] = Field(default=None, description="SIEM or signature rule ID if matched")
    severity: str = Field(default="low", description="low, medium, high, critical")
    
    provenance: EventProvenance = Field(default_factory=EventProvenance)
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Preserved original raw telemetry payload")

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            try:
                # Replace trailing 'Z' if present
                clean_str = v.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(clean_str)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except Exception:
                return datetime.now(timezone.utc)
        return datetime.now(timezone.utc)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> str:
        if not isinstance(v, str):
            return "low"
        val = v.strip().lower()
        if val in ("critical", "high", "medium", "low", "info"):
            return val
        return "low"


def normalize_event(raw: Dict[str, Any], default_source: str = "wazuh") -> NormalizedEvent:
    """
    Safely converts a legacy event dictionary, Wazuh JSON alert, or CloudTrail record
    into a validated NormalizedEvent. Tolerates missing, malformed, or dirty inputs.
    """
    if not isinstance(raw, dict):
        return NormalizedEvent(description="Empty or invalid event object", status="error")

    # Extract ID
    event_id = str(raw.get("id") or raw.get("event_id") or f"EVT-{str(uuid.uuid4())[:8]}")

    # Timestamp
    ts = raw.get("timestamp") or raw.get("@timestamp") or datetime.now(timezone.utc)

    # Principal
    user_val = raw.get("user") or raw.get("dstuser") or raw.get("srcuser") or "unknown"
    if isinstance(raw.get("data"), dict):
        d = raw["data"]
        user_val = d.get("dstuser") or d.get("srcuser") or user_val
    principal = PrincipalInfo(
        identity=str(user_val),
        principal_type="machine" if any(k in str(user_val).lower() for k in ("svc", "bot", "worker", "lambda", "daemon")) else "human",
        arn=raw.get("arn")
    )

    # Network
    src_ip = raw.get("src_ip")
    dst_ip = raw.get("dst_ip")
    if not src_ip and isinstance(raw.get("data"), dict):
        src_ip = raw["data"].get("srcip")
    if not dst_ip and isinstance(raw.get("data"), dict):
        dst_ip = raw["data"].get("dstip")
    if not src_ip and raw.get("location"):
        src_ip = str(raw["location"]).split("->")[0].strip()

    network = NetworkInfo(
        src_ip=str(src_ip or "unknown"),
        dst_ip=str(dst_ip or "unknown"),
        src_port=int(raw.get("src_port") or 0) if str(raw.get("src_port", "")).isdigit() else None,
        dst_port=int(raw.get("dst_port") or 0) if str(raw.get("dst_port", "")).isdigit() else None,
        protocol=raw.get("protocol")
    )

    # Volumetric / Flow Metrics
    src_bytes = int(raw.get("src_bytes") or raw.get("bytes_transferred") or 0)
    dst_bytes = int(raw.get("dst_bytes") or 0)
    failed_attempts = int(raw.get("failed_attempts") or 0)
    duration = float(raw.get("duration") or 0.0)

    # Safe float rates [0.0, 1.0]
    def _clamp_rate(v: Any, default: float) -> float:
        try:
            val = float(v)
            return max(0.0, min(1.0, val))
        except (ValueError, TypeError):
            return default

    # Ingestion provenance
    is_simulated = raw.get("event_type") == "attack" or "SIM-" in event_id or default_source == "synthetic"
    provenance = EventProvenance(
        collector=str(raw.get("source") or default_source),
        ingest_mode="simulated" if is_simulated else "live"
    )

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source_type=str(raw.get("source") or default_source),
        source_identifier=raw.get("source_identifier"),
        principal=principal,
        network=network,
        service=raw.get("service") or raw.get("program_name"),
        action=raw.get("action") or raw.get("rule_description") or "unknown",
        target_resource=raw.get("resource") or raw.get("target_resource"),
        status=str(raw.get("status") or "detected"),
        duration=max(0.0, duration),
        src_bytes=max(0, src_bytes),
        dst_bytes=max(0, dst_bytes),
        failed_attempts=max(0, failed_attempts),
        count=max(0, int(raw.get("count") or 1)),
        srv_count=max(0, int(raw.get("srv_count") or 1)),
        serror_rate=_clamp_rate(raw.get("serror_rate"), 0.0),
        rerror_rate=_clamp_rate(raw.get("rerror_rate"), 0.0),
        same_srv_rate=_clamp_rate(raw.get("same_srv_rate"), 1.0),
        diff_srv_rate=_clamp_rate(raw.get("diff_srv_rate"), 0.0),
        description=raw.get("description") or raw.get("rule_description") or "",
        rule_id=int(raw.get("rule_id")) if str(raw.get("rule_id", "")).isdigit() else None,
        severity=str(raw.get("severity") or "low"),
        provenance=provenance,
        raw_payload=raw
    )
